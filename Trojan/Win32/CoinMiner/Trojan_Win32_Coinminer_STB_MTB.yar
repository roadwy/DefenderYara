
rule Trojan_Win32_Coinminer_STB_MTB{
	meta:
		description = "Trojan:Win32/Coinminer.STB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 24 4e f7 9f 96 46 50 bf 42 03 18 31 09 ff 2e 21 d8 97 9b 6d d4 c2 b6 cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}