
rule TrojanSpy_BAT_Omaneat_H_bit{
	meta:
		description = "TrojanSpy:BAT/Omaneat.H!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7c 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 7c 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 |System.Resources.ResourceManager|Invoke
		$a_03_1 = {03 50 06 03 50 06 91 02 7b ?? ?? ?? ?? 06 02 7b ?? ?? ?? ?? 8e 69 5d 91 61 28 ?? ?? ?? ?? 9c 06 17 58 0a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}