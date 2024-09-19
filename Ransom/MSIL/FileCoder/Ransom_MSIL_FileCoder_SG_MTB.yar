
rule Ransom_MSIL_FileCoder_SG_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 69 74 72 6f 52 61 6e 73 6f 6d 77 61 72 65 2e 52 65 73 6f 75 72 63 65 73 2e 77 6c 2e 70 6e 67 } //2 NitroRansomware.Resources.wl.png
		$a_01_1 = {24 64 35 65 38 37 34 33 39 2d 32 31 65 36 2d 34 35 36 37 2d 61 38 37 37 2d 36 61 64 39 62 65 65 30 30 64 63 39 } //2 $d5e87439-21e6-4567-a877-6ad9bee00dc9
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}