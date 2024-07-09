
rule Trojan_Win32_Dyloader_A_bit{
	meta:
		description = "Trojan:Win32/Dyloader.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 30 88 0c 38 88 1c 30 8b 75 0c 02 1c 38 8a 0c 16 0f b6 db 32 0c 18 8b 5d 10 88 0c 13 42 eb } //1
		$a_03_1 = {66 8b 0c 46 8d 95 ?? ?? ff ff 83 f1 08 88 8c 05 ?? ?? ff ff 40 83 f8 08 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}