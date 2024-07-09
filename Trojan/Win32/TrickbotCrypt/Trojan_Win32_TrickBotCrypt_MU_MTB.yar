
rule Trojan_Win32_TrickBotCrypt_MU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 [0-04] 51 50 c7 [0-06] 59 bb [0-04] 89 [0-02] 33 [0-07] 31 ?? 8b [0-02] c7 [0-06] d3 ?? 8a ?? 8a ?? d3 ?? ff [0-02] 75 ?? 59 53 8f [0-02] ff [0-02] 58 aa 49 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}