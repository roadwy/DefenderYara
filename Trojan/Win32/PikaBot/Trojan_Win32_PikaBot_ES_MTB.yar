
rule Trojan_Win32_PikaBot_ES_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 db 8d 4d ?? 45 be ?? ?? ?? ?? 32 ed 34 ?? 4b d7 32 3e 32 ad ?? ?? ?? ?? a5 } //1
		$a_00_1 = {43 72 61 73 68 } //1 Crash
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}