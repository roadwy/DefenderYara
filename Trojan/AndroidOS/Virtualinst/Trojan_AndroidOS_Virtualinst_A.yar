
rule Trojan_AndroidOS_Virtualinst_A{
	meta:
		description = "Trojan:AndroidOS/Virtualinst.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 6e 7a 69 70 46 69 6c 65 2b 2c 74 65 6d 70 44 69 72 3d } //01 00  unzipFile+,tempDir=
		$a_01_1 = {75 70 64 61 74 65 20 73 6f 46 69 6c 65 73 3d } //00 00  update soFiles=
	condition:
		any of ($a_*)
 
}