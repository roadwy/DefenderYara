
rule Trojan_Win32_RedLine_DDA_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 37 34 ac 2c 65 34 22 2c 73 68 ?? ?? ?? ?? 88 04 37 e8 ?? ?? ?? ?? 30 04 37 83 c4 1c 46 3b 75 18 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}