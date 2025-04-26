
rule Trojan_Win32_Zlob_AT{
	meta:
		description = "Trojan:Win32/Zlob.AT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 85 f0 fd ff ff 50 e8 ?? ?? ?? ?? [0-02] 59 59 f7 d8 1b c0 f7 d8 88 85 ?? fd ff ff } //1
		$a_03_1 = {eb 07 8b 45 c4 40 89 45 c4 8b 45 c4 3b 45 ec 73 (2a|2b) ff 75 0c e8 ?? fe ff ff [0-66] 89 45 c0 0f b7 45 c0 35 ?? ?? 00 00 50 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}