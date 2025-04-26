
rule Trojan_Win64_IcedId_PAE_MTB{
	meta:
		description = "Trojan:Win64/IcedId.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 5f 67 73 73 5f 63 5f 61 74 74 72 5f 6c 6f 63 61 6c 5f 6c 6f 67 69 6e 5f 75 73 65 72 } //1 t_gss_c_attr_local_login_user
		$a_01_1 = {67 73 73 73 70 69 5f 61 63 71 75 69 72 65 5f 63 72 65 64 5f 77 69 74 68 5f 70 61 73 73 77 6f 72 64 } //1 gssspi_acquire_cred_with_password
		$a_01_2 = {74 5f 67 73 73 5f 63 5f 6e 74 5f 68 6f 73 74 62 61 73 65 64 5f 73 65 72 76 69 63 65 5f 78 5f 6f 69 64 5f 64 65 73 63 } //1 t_gss_c_nt_hostbased_service_x_oid_desc
		$a_01_3 = {74 5f 67 73 73 5f 6b 72 62 35 5f 65 78 70 6f 72 74 5f 6c 75 63 69 64 5f 63 6f 6e 74 65 78 74 5f 78 5f 6f 69 64 5f 64 65 73 63 } //1 t_gss_krb5_export_lucid_context_x_oid_desc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}