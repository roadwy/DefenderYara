
rule Trojan_BAT_ClipBanker_NBL_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {63 20 6d 86 b2 26 58 66 20 ?? ?? ?? f6 59 20 ?? ?? ?? 09 58 20 ?? ?? ?? f3 61 20 ?? ?? ?? 14 61 5f 91 fe 09 02 00 60 61 d1 9d } //5
		$a_01_1 = {46 4e 69 6e 74 65 72 6e 61 6c 2e 65 78 65 } //1 FNinternal.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}