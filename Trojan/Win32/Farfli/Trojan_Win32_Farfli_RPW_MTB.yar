
rule Trojan_Win32_Farfli_RPW_MTB{
	meta:
		description = "Trojan:Win32/Farfli.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8a 1e 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 d1 32 d3 40 f6 d2 88 16 41 46 66 3b cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}