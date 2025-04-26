
rule Trojan_Win64_CobaltStrike_ASD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {41 63 63 65 73 73 20 76 69 6f 6c 61 74 69 6f 6e 20 63 61 75 67 68 74 2c 20 64 65 63 72 79 70 74 69 6e 67 20 6d 65 6d 6f 72 79 } //1 Access violation caught, decrypting memory
		$a_81_1 = {64 72 6f 70 20 6f 66 20 74 68 65 20 70 61 6e 69 63 20 70 61 79 6c 6f 61 64 20 70 61 6e 69 63 6b 65 64 } //1 drop of the panic payload panicked
		$a_01_2 = {31 c0 48 39 c2 74 08 f6 14 01 48 ff c0 eb f3 } //2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}