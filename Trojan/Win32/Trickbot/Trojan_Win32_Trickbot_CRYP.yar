
rule Trojan_Win32_Trickbot_CRYP{
	meta:
		description = "Trojan:Win32/Trickbot.CRYP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 00 10 00 00 [0-02] 59 [0-02] 52 e2 fd [0-03] 8b ec [0-02] 05 ?? ?? ?? ?? 68 f1 ff 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}