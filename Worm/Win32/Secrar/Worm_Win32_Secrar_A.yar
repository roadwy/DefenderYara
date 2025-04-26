
rule Worm_Win32_Secrar_A{
	meta:
		description = "Worm:Win32/Secrar.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 04 8d 45 ?? 50 6a 1e 6a ff ff 55 fc 85 c0 75 04 b0 01 eb } //1
		$a_03_1 = {8b 55 08 03 14 81 52 e8 ?? ?? ?? ?? 83 c4 04 3b 45 0c 75 0f 8b 45 ?? 8b 4d ?? 0f b7 14 41 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}