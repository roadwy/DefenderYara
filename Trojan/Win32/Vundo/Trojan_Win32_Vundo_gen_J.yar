
rule Trojan_Win32_Vundo_gen_J{
	meta:
		description = "Trojan:Win32/Vundo.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 5e 6a 02 53 88 1f 6a d8 88 1e 8b 35 ?? ?? ?? ?? 50 ff d6 83 f8 ff 74 14 53 8d 45 fc 50 6a 14 57 } //1
		$a_03_1 = {74 2b 56 56 6a 4e 57 ff 15 ?? ?? ?? ?? 83 f8 ff 74 14 56 8d 45 0c 50 ff 75 10 53 57 ff 15 } //1
		$a_03_2 = {83 f8 04 7e 25 8d 74 30 fc bf ?? ?? ?? ?? 57 56 ff 15 ?? ?? ?? ?? 85 c0 74 22 83 c3 05 83 c7 05 83 fb 0f 72 e9 8b 7d f0 33 db ff 45 f8 8b 45 f8 83 45 fc 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}