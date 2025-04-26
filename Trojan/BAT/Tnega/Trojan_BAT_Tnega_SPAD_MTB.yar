
rule Trojan_BAT_Tnega_SPAD_MTB{
	meta:
		description = "Trojan:BAT/Tnega.SPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 00 74 00 6d 00 6f 00 75 00 6c 00 64 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 61 00 6e 00 64 00 65 00 72 00 2f 00 51 00 66 00 75 00 75 00 64 00 2e 00 62 00 6d 00 70 00 } //1 dtmoulding.com/wander/Qfuud.bmp
		$a_01_1 = {54 00 6c 00 6b 00 63 00 73 00 78 00 6b 00 66 00 62 00 73 00 6a 00 70 00 69 00 72 00 78 00 76 00 6d 00 63 00 73 00 69 00 64 00 78 00 6f 00 2e 00 41 00 68 00 6e 00 68 00 62 00 71 00 64 00 7a 00 6e 00 6d 00 } //1 Tlkcsxkfbsjpirxvmcsidxo.Ahnhbqdznm
		$a_81_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_81_3 = {54 6f 42 79 74 65 } //1 ToByte
		$a_81_4 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}