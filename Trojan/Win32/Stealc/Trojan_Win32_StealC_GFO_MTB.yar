
rule Trojan_Win32_StealC_GFO_MTB{
	meta:
		description = "Trojan:Win32/StealC.GFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 39 45 10 76 1b 8b 55 fc 8b 45 0c 01 d0 8b 4d fc 8b 55 08 01 ca 0f b6 00 88 02 83 45 fc 01 eb } //10
		$a_01_1 = {40 2e 65 68 5f 66 72 61 6d } //1 @.eh_fram
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}