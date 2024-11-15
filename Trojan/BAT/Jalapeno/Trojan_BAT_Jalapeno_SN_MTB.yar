
rule Trojan_BAT_Jalapeno_SN_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {38 61 65 35 30 63 33 39 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 8ae50c39.Resources.resources
		$a_81_1 = {24 64 32 64 32 32 61 37 38 2d 63 64 34 65 2d 34 64 39 39 2d 61 39 64 65 2d 33 30 36 64 36 36 32 35 35 38 62 35 } //1 $d2d22a78-cd4e-4d99-a9de-306d662558b5
		$a_81_2 = {50 72 6f 44 52 45 4e 41 4c 49 4e 2e 65 78 65 } //1 ProDRENALIN.exe
		$a_81_3 = {70 72 6f 44 41 44 20 32 30 31 33 2d 32 30 31 37 } //1 proDAD 2013-2017
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}