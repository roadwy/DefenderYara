
rule TrojanDownloader_BAT_Tidotick_A{
	meta:
		description = "TrojanDownloader:BAT/Tidotick.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 69 6d 65 72 32 5f 54 69 63 6b } //1 Timer2_Tick
		$a_03_1 = {00 0a 00 02 6f ?? 00 00 06 16 6f ?? 00 00 0a 00 72 ?? ?? 00 70 0a 1d 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 0c 08 2c 07 07 28 ?? 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}