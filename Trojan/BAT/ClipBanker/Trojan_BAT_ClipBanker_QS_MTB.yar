
rule Trojan_BAT_ClipBanker_QS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.QS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 39 64 65 62 64 39 39 65 2d 32 62 36 36 2d 34 37 62 36 2d 61 33 32 37 2d 33 36 63 37 37 37 65 33 38 30 65 66 } //1 $9debd99e-2b66-47b6-a327-36c777e380ef
		$a_81_1 = {53 68 69 6e 6f 62 75 43 6c 69 70 70 65 72 2d 6d 61 73 74 65 72 } //1 ShinobuClipper-master
		$a_81_2 = {43 6c 69 70 70 65 72 5c 43 6c 69 70 70 65 72 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 4f 62 66 75 73 63 61 74 65 64 5c 49 6e 63 2e 49 6e 66 72 61 73 74 72 75 63 74 75 72 20 48 6f 73 74 20 64 72 69 76 65 72 2e 70 64 62 } //1 Clipper\Clipper\bin\Release\Obfuscated\Inc.Infrastructur Host driver.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}