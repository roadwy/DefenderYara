
rule Trojan_BAT_Barys_NBA_MTB{
	meta:
		description = "Trojan:BAT/Barys.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 2e 03 16 2b 05 17 11 1b 13 1b 17 59 } //2
		$a_01_1 = {11 3d 2c 03 16 2b 01 17 17 59 } //1 㴑̬⬖ᜁ夗
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}