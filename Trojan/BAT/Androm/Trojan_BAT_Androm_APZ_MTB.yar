
rule Trojan_BAT_Androm_APZ_MTB{
	meta:
		description = "Trojan:BAT/Androm.APZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 0b 00 00 04 07 9a 06 17 28 ?? ?? ?? 0a 2d 12 7e 0c 00 00 04 07 9a } //2
		$a_01_1 = {69 00 52 00 65 00 6d 00 6f 00 76 00 61 00 6c 00 50 00 72 00 6f 00 57 00 50 00 46 00 2e 00 65 00 78 00 65 00 } //1 iRemovalProWPF.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}