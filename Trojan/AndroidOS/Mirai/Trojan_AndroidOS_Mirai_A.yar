
rule Trojan_AndroidOS_Mirai_A{
	meta:
		description = "Trojan:AndroidOS/Mirai.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 67 6c 6f 62 61 6c 2e 6c 61 74 69 6e 6f 74 76 6f 64 } //1 com.global.latinotvod
		$a_01_1 = {63 6f 6d 2e 69 6a 6d 2e 64 61 74 61 65 6e 63 72 79 70 74 69 6f 6e 2e 44 45 54 6f 6f 6c } //1 com.ijm.dataencryption.DETool
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}