
rule Ransom_Win32_GandCrab_AI_bit{
	meta:
		description = "Ransom:Win32/GandCrab.AI!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 08 03 45 fc 0f be 18 e8 6d ff ff ff 33 d8 8b 45 08 03 45 fc 88 18 eb } //1
		$a_01_1 = {64 a1 2c 00 00 00 8b 00 c7 40 04 01 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}