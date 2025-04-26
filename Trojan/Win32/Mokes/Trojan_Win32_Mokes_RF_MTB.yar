
rule Trojan_Win32_Mokes_RF_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ec 81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ?? 56 33 f6 85 db 7e ?? e8 ?? ?? ?? ?? 30 04 37 83 fb 19 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}