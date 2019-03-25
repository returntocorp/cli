# Needed to deconflict `r2c` namespace with other packages in `r2c`
import pkg_resources

pkg_resources.declare_namespace(__name__)
