
rule Trojan_Win32_Dofoil_ASN_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 f1 89 4d d0 89 f0 89 45 cc 89 f9 80 c9 01 99 f7 f9 89 45 c4 } //1
		$a_01_1 = {63 3e 67 74 71 20 74 63 20 3e 76 6e 66 65 72 3e 65 3e 65 75 3e 72 2f 73 65 65 72 65 74 20 6b 65 74 65 20 74 73 65 75 20 76 64 6c 75 50 65 74 65 3c 3e 63 61 74 20 6c 73 72 73 79 65 65 3e 65 65 20 74 45 72 20 6c 69 69 20 64 74 69 69 6f 73 } //1 c>gtq tc >vnfer>e>eu>r/seeret kete tseu vdluPete<>cat lsrsyee>ee tEr lii dtiios
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}