
rule Trojan_Win32_Jaku_F_dha{
	meta:
		description = "Trojan:Win32/Jaku.F!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 73 65 6c 66 2e 62 61 74 00 69 6d 20 77 75 61 75 63 6c 74 2e 65 78 65 0d 0a 0d 0a 64 65 6c 20 2f 66 20 2f 71 20 22 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 53 74 61 72 74 75 70 5c 77 75 61 75 63 6c 74 2e 65 78 65 22 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}