
rule Worm_Win32_Bymot_A{
	meta:
		description = "Worm:Win32/Bymot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 72 64 5f 73 6e } //1 mrd_sn
		$a_01_1 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c 25 73 3e } //1 MAIL FROM: <%s>
		$a_01_2 = {41 74 6d 53 74 61 74 3a 20 61 69 64 3d 25 64 20 54 3d 25 64 20 47 3d 25 64 20 42 3d 25 64 20 28 62 6c 3d 25 64 2c 6e 6f 75 73 65 72 3d 25 64 2c 6e 6f 6d 78 3d 25 64 2c 69 6f 65 72 72 3d 25 64 2c 65 72 72 3d 25 64 2c 65 5f 63 6f 6e 6e 3d 25 64 2c 65 5f 63 6f 6e 6e 5f 72 65 6a 3d 25 64 2c 65 5f 69 6e 74 65 72 6e 3d 25 64 29 } //1 AtmStat: aid=%d T=%d G=%d B=%d (bl=%d,nouser=%d,nomx=%d,ioerr=%d,err=%d,e_conn=%d,e_conn_rej=%d,e_intern=%d)
		$a_01_3 = {53 54 41 54 42 55 53 59 } //1 STATBUSY
		$a_01_4 = {72 65 74 72 79 69 70 5f 65 6e 61 62 6c 65 64 } //1 retryip_enabled
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}