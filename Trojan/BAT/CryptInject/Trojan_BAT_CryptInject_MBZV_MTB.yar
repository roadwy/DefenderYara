
rule Trojan_BAT_CryptInject_MBZV_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.MBZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 69 67 71 79 64 76 78 74 00 3c 4d 6f 64 75 6c 65 3e 00 49 6e 66 6f 49 6e 76 6f 63 61 74 69 6f 6e 44 65 66 00 41 69 67 71 79 64 76 78 74 } //10 楁照摹硶t䴼摯汵㹥䤀普䥯癮捯瑡潩䑮晥䄀杩祱癤瑸
		$a_01_1 = {51 74 6c 6e 79 79 71 68 69 6f 6c 2e 41 6e 6e 6f 74 61 74 69 6f 6e 73 } //1 Qtlnyyqhiol.Annotations
		$a_01_2 = {5a 69 70 41 6e 64 41 65 73 } //1 ZipAndAes
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}