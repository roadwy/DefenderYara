
rule TrojanDropper_O97M_Donoff_RPI_MTB{
	meta:
		description = "TrojanDropper:O97M/Donoff.RPI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 73 74 72 72 65 76 65 72 73 65 28 22 30 2e 36 2e 70 74 74 68 6c 6d 78 72 65 76 72 65 73 2e 32 6c 6d 78 73 6d 22 29 29 77 69 6e 68 74 74 70 72 65 71 2e 6f 70 65 6e 22 70 6f 73 74 22 2c 22 68 74 74 70 73 3a 2f 2f 62 64 76 6f 6c 74 61 69 72 65 2d 62 38 64 61 2e 72 65 73 74 64 62 2e 69 6f 2f 72 65 73 74 2f 64 6f 63 63 75 6d 65 6e 74 22 } //1 =createobject(strreverse("0.6.ptthlmxrevres.2lmxsm"))winhttpreq.open"post","https://bdvoltaire-b8da.restdb.io/rest/doccument"
		$a_01_1 = {3d 67 65 74 6f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 7b 69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 6c 65 76 65 6c 3d 69 6d 70 65 72 73 6f 6e 61 74 65 7d 21 5c 5c 2e 5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 3a 73 74 64 72 65 67 70 72 6f 76 22 29 72 3d 6f 72 65 67 2e 73 65 74 73 74 72 69 6e 67 76 61 6c 75 65 28 68 6b 65 79 5f 63 75 72 72 65 6e 74 5f 75 73 65 72 2c 73 74 72 72 65 76 65 72 73 65 28 22 6e 75 72 5c 6e 6f 69 73 72 65 76 74 6e 65 72 72 75 63 5c 73 77 6f 64 6e 69 77 5c 74 66 6f 73 6f 72 63 69 6d 5c 65 72 61 77 74 66 6f 73 22 29 2c 6e 2c 73 74 72 72 65 76 65 72 73 65 28 22 65 78 65 2e 74 73 6f 68 6e 6f 63 5c 32 33 6d 65 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 26 76 29 65 6e 64 73 75 62 } //1 =getobject("winmgmts:{impersonationlevel=impersonate}!\\.\root\default:stdregprov")r=oreg.setstringvalue(hkey_current_user,strreverse("nur\noisrevtnerruc\swodniw\tfosorcim\erawtfos"),n,strreverse("exe.tsohnoc\23metsys\swodniw\:c")&v)endsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}