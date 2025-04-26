
rule Trojan_BAT_PureLogStealer_MBXT_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {71 52 44 77 41 4d 4f 39 00 64 51 45 76 61 6e 42 54 34 36 71 6a 66 55 48 } //3 剱睄䵁㥏搀䕑慶䉮㑔然晪䡕
		$a_01_1 = {4d 65 73 68 45 6b 72 61 6e 2e 44 61 74 61 53 65 74 6c 65 72 2e 46 69 72 6d 61 44 42 4c 69 73 74 44 } //2 MeshEkran.DataSetler.FirmaDBListD
		$a_01_2 = {64 66 35 61 32 34 35 38 63 62 33 35 } //1 df5a2458cb35
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}