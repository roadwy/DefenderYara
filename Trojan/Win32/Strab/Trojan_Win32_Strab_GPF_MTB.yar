
rule Trojan_Win32_Strab_GPF_MTB{
	meta:
		description = "Trojan:Win32/Strab.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {64 65 65 72 6c 65 74 74 75 63 65 2e 78 79 7a 2f 70 61 6e 2e 70 68 70 3f 70 65 } //deerlettuce.xyz/pan.php?pe  5
		$a_80_1 = {66 6f 72 63 65 72 65 61 63 74 69 6f 6e 2e 78 79 7a 2f 70 69 6e 2e 70 68 70 3f 70 65 } //forcereaction.xyz/pin.php?pe  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}