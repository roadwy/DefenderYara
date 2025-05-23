
rule Trojan_BAT_Kryptik_VC_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 10 00 06 00 00 "
		
	strings :
		$a_03_0 = {0b 07 19 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 7e ?? ?? ?? ?? a2 25 18 72 ?? ?? ?? ?? a2 28 ?? ?? ?? ?? 26 20 ?? ?? ?? ?? 0a 2b 00 06 2a } //10
		$a_03_1 = {0d 07 09 6f ?? ?? ?? ?? ?? 07 18 6f ?? ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 03 16 03 8e 69 6f ?? ?? ?? ?? 13 04 11 04 0a 2b 00 06 2a } //10
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  2
		$a_80_3 = {57 53 54 52 42 75 66 66 65 72 4d 61 72 73 68 61 6c 65 72 } //WSTRBufferMarshaler  2
		$a_80_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  2
		$a_80_5 = {41 63 74 69 76 61 74 6f 72 } //Activator  2
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2) >=16
 
}