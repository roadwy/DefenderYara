
rule Trojan_Win64_AVTamper_D_ldr{
	meta:
		description = "Trojan:Win64/AVTamper.D!ldr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 61 69 6c 65 64 21 0a 00 65 72 90 01 01 6f 72 20 25 64 0a 00 42 49 4e 41 52 59 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}