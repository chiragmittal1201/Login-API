const buildUserFilter = (query) => {

    const {

        search,
        role,
        status

    } = query;

    // ====================== FILTER OBJECT ======================

    let filter = {};

    // ====================== SEARCH ======================

    if (search) {

        filter.$or = [

            {
                name: {
                    $regex: search,
                    $options: "i"
                }
            },

            {
                email: {
                    $regex: search,
                    $options: "i"
                }
            },

            {
                phone: {
                    $regex: search,
                    $options: "i"
                }
            }
        ];
    }

    // ====================== ROLE FILTER ======================

    if (role) {

        filter.role = role;
    }

    // ====================== REQUEST STATUS FILTER ======================

    if (status) {

        filter.managerRequestStatus =
            status;
    }

    // ====================== RETURN FILTER ======================

    return filter;
};

module.exports = buildUserFilter;