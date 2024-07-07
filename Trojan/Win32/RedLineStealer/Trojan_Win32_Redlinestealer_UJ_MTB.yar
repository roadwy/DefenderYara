
rule Trojan_Win32_Redlinestealer_UJ_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.UJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 c7 8a 10 8a ca 80 f1 90 01 01 88 08 5f 3a ca 74 90 01 01 ff 15 90 01 04 c9 c3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}