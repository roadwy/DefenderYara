
rule PWS_Win32_Zbot_KM{
	meta:
		description = "PWS:Win32/Zbot.KM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 49 41 49 60 61 41 49 8b 07 33 db 8a 5c 30 ff 41 49 90 90 83 f3 0d 41 49 90 90 8b c7 e8 ?? ?? ?? ?? 33 dd 88 5c 30 ff 90 90 41 49 90 90 8b 07 8a 5c 30 ff 80 f3 1c 80 f3 0d 81 e3 ff 00 00 00 41 49 90 90 41 49 8b c7 e8 ?? ?? ?? ?? 88 5c 30 ff 90 90 60 61 83 fd 21 75 07 bd 01 00 00 00 eb 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}