
rule Trojan_Win32_EmotetCrypt_PCB_MTB{
	meta:
		description = "Trojan:Win32/EmotetCrypt.PCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 0f 02 c3 02 d3 88 14 0f 88 04 29 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8b 74 24 24 46 89 74 24 24 03 54 24 18 0f b6 04 0a 8b 54 24 10 02 c3 32 44 32 ff 83 6c 24 14 01 88 46 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}