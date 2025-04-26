
rule Trojan_Win32_Viewsure_D_dha{
	meta:
		description = "Trojan:Win32/Viewsure.D!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 44 43 41 00 00 00 47 64 69 33 32 2e 64 6c 6c 00 00 00 4d 69 63 72 6f 73 6f 66 74 20 58 50 53 20 44 6f 63 75 6d 65 6e 74 20 57 72 69 74 65 72 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}