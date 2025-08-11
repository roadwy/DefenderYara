
rule Backdoor_BAT_DcRat_SN_MTB{
	meta:
		description = "Backdoor:BAT/DcRat.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 32 66 39 32 66 32 66 39 2d 64 66 65 66 2d 34 32 35 39 2d 62 66 32 61 2d 39 64 62 39 65 63 35 64 38 35 35 63 } //2 $2f92f2f9-dfef-4259-bf2a-9db9ec5d855c
		$a_81_1 = {42 58 43 4a 44 46 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 BXCJDF.Properties.Resources
		$a_81_2 = {42 58 43 4a 44 46 2e 65 78 65 } //2 BXCJDF.exe
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}