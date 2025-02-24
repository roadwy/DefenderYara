
rule Trojan_BAT_Zusy_HNE_MTB{
	meta:
		description = "Trojan:BAT/Zusy.HNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 00 75 52 4c 6d 4f 4e 00 00 00 00 } //2
		$a_01_1 = {6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 00 2e 63 74 6f 72 } //1 獭潣汲扩匀獹整m扏敪瑣唀䱒潄湷潬摡潔楆敬⸀瑣牯
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}