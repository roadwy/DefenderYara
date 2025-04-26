
rule PWS_Win32_Steam_P_bit{
	meta:
		description = "PWS:Win32/Steam.P!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 74 65 61 6d 48 6f 6f 6b 5c 6e 65 77 5c 53 74 65 61 6d 47 68 6f 73 74 5c 52 65 6c 65 61 73 65 5c 49 6e 6a 65 63 74 69 6f 6e 2e 70 64 62 } //1 SteamHook\new\SteamGhost\Release\Injection.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}