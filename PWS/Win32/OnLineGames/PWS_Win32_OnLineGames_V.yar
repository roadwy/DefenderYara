
rule PWS_Win32_OnLineGames_V{
	meta:
		description = "PWS:Win32/OnLineGames.V,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 02 56 6a fc 57 ff d3 8d 45 f8 56 8b 35 ?? ?? ?? ?? 50 8d 45 f4 6a 04 50 57 ff d6 81 7d f4 fe db 43 bd 74 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}