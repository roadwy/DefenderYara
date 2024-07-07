
rule TrojanSpy_Win32_Webmoner_P{
	meta:
		description = "TrojanSpy:Win32/Webmoner.P,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 75 74 65 41 00 4f 20 44 41 20 4e 49 47 45 52 } //1 畣整A⁏䅄丠䝉剅
	condition:
		((#a_01_0  & 1)*1) >=1
 
}