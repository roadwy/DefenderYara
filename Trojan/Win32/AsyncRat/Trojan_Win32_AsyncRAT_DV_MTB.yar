
rule Trojan_Win32_AsyncRAT_DV_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 68 90 01 01 67 42 00 ff 15 48 c1 41 00 8b d8 85 db 75 1b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}