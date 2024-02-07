
rule TrojanDownloader_O97M_Ursnif_PDE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PDE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 72 65 70 6c 61 63 65 28 72 74 72 69 6d 28 63 76 73 5f 6c 69 73 74 28 66 65 74 69 63 69 73 6d 6f 29 29 2c 22 2d 22 2c 22 61 61 22 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e } //01 00  =replace(rtrim(cvs_list(feticismo)),"-","aa")endfunctionfunction
		$a_01_1 = {6c 65 6e 28 67 65 73 74 69 76 6f 29 29 66 6f 72 73 62 61 76 61 3d 31 74 6f 63 61 6d 70 61 67 6e 6f 6c 61 28 79 6f 6b 6f 68 61 6d 61 29 79 6f 6b 6f 68 61 6d 61 28 73 62 61 76 61 29 3d 6d 69 64 28 67 65 73 74 69 76 6f 2c 73 62 61 76 61 2c 31 29 6e 65 78 74 66 6f 72 65 61 63 68 69 6e 64 6f 73 } //01 00  len(gestivo))forsbava=1tocampagnola(yokohama)yokohama(sbava)=mid(gestivo,sbava,1)nextforeachindos
		$a_01_2 = {3d 6d 69 64 28 73 74 72 64 61 74 61 2c 35 29 77 65 6e 64 64 65 63 6f 64 65 62 61 73 65 36 34 3d 6f 75 74 61 72 72 61 79 65 6e 64 66 75 6e 63 74 69 6f 6e 70 75 62 6c 69 63 66 75 6e 63 74 69 6f 6e 66 75 63 68 69 6e 6e 69 28 72 6e 67 61 73 73 74 72 69 6e 67 29 63 6e 74 3d 33 37 33 36 66 75 63 68 69 6e 6e 69 3d 72 69 67 68 74 28 72 6e 67 2c 6c 65 6e 28 72 6e 67 29 2d 63 6e 74 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 61 62 62 } //01 00  =mid(strdata,5)wenddecodebase64=outarrayendfunctionpublicfunctionfuchinni(rngasstring)cnt=3736fuchinni=right(rng,len(rng)-cnt)endfunctionfunctionabb
		$a_01_3 = {3d 62 72 65 76 65 74 74 61 74 6f 28 6c 65 66 74 28 65 6e 76 69 72 6f 6e 28 63 6f 6a 6f 6e 65 73 28 22 35 2d 33 38 63 2d 6f 30 6d 39 73 37 70 31 30 31 65 63 33 22 29 29 2c 32 30 29 26 63 6f 6a 6f 6e 65 73 28 22 2d 31 31 72 33 2d 65 38 30 67 2c 73 37 31 30 76 2d 38 72 31 22 29 26 22 33 32 2e 22 26 63 6f 6a 6f 6e 65 73 } //00 00  =brevettato(left(environ(cojones("5-38c-o0m9s7p101ec3")),20)&cojones("-11r3-e80g,s710v-8r1")&"32."&cojones
	condition:
		any of ($a_*)
 
}