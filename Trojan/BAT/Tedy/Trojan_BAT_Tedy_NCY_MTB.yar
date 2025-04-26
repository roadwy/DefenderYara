
rule Trojan_BAT_Tedy_NCY_MTB{
	meta:
		description = "Trojan:BAT/Tedy.NCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 15 00 00 0a 0d 08 19 18 73 ?? ?? ?? 0a 0a 09 07 16 07 8e 69 6f ?? ?? ?? 0a 00 06 09 6f ?? ?? ?? 0a 16 09 6f ?? ?? ?? 0a 8e 69 6f ?? ?? ?? 0a } //5
		$a_01_1 = {46 72 65 65 57 61 79 50 68 61 6e 74 6f 6d } //1 FreeWayPhantom
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}