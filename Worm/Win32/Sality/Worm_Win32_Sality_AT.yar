
rule Worm_Win32_Sality_AT{
	meta:
		description = "Worm:Win32/Sality.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 94 05 b3 fa ff ff 83 fa 5c 74 12 68 } //1
		$a_03_1 = {83 fa 50 7e 29 e8 ?? ?? ?? ?? 25 ff ff 00 00 99 b9 3c 00 00 00 f7 f9 8b 14 95 ?? ?? ?? ?? 52 8d 85 00 fc ff ff 50 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}