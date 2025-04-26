
rule Trojan_Win32_Upatreld{
	meta:
		description = "Trojan:Win32/Upatreld,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 65 72 33 32 2e 62 69 6e 00 6c 6f 61 64 65 72 43 6f 6e 66 69 67 53 6f 75 72 63 65 00 } //1 潬摡牥㈳戮湩氀慯敤䍲湯楦卧畯捲e
	condition:
		((#a_01_0  & 1)*1) >=1
 
}