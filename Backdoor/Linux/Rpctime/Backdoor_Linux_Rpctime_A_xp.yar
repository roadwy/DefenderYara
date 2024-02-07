
rule Backdoor_Linux_Rpctime_A_xp{
	meta:
		description = "Backdoor:Linux/Rpctime.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 64 72 5f 6c 6f 6e 67 } //01 00  xdr_long
		$a_01_1 = {78 64 72 5f 77 72 61 70 73 74 72 69 6e 67 } //01 00  xdr_wrapstring
		$a_01_2 = {52 50 43 20 54 49 4d 45 20 42 41 43 4b 44 4f 4f 52 } //01 00  RPC TIME BACKDOOR
		$a_01_3 = {44 45 41 44 48 30 55 52 } //00 00  DEADH0UR
	condition:
		any of ($a_*)
 
}