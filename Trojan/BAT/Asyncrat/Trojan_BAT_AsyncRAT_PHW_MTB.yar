
rule Trojan_BAT_AsyncRAT_PHW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {78 73 70 79 6d 61 69 6e 2e 67 69 74 68 75 62 2e 69 6f } //xspymain.github.io  2
		$a_80_1 = {49 6e 76 6f 6b 65 52 61 6e 64 6f 6d 4d 65 74 68 6f 64 } //InvokeRandomMethod  1
		$a_80_2 = {43 72 65 61 74 65 50 61 79 6c 6f 61 64 54 68 72 65 61 64 } //CreatePayloadThread  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=4
 
}