
rule Trojan_Win32_Glupteba_DHJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3b fe 7c 0b e8 ?? ?? ?? ?? 30 04 1f 4f 79 f5 8b 4d fc 5f 5e 33 cd } //1
		$a_02_1 = {0f b6 cb 03 c1 8b 4d fc 5f 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 5e 33 cd } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}