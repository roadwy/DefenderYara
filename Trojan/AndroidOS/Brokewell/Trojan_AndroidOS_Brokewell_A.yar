
rule Trojan_AndroidOS_Brokewell_A{
	meta:
		description = "Trojan:AndroidOS/Brokewell.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 57 6c 70 61 57 6c 70 61 57 6c 70 61 57 6c 70 61 57 6c 70 61 65 56 55 33 4a 48 55 35 33 44 32 6c 39 36 39 6f 2f 42 4e 39 72 77 3d } //1 aWlpaWlpaWlpaWlpaWlpaeVU3JHU53D2l969o/BN9rw=
		$a_01_1 = {51 70 48 34 56 38 34 68 57 6f 6e 55 65 76 72 63 39 67 6a 70 77 3d } //1 QpH4V84hWonUevrc9gjpw=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}