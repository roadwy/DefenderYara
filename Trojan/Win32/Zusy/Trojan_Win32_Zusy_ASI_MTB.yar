
rule Trojan_Win32_Zusy_ASI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 31 32 2e 31 37 35 2e 36 39 2e 37 37 20 70 6b 35 35 35 2e 63 6f 6d 20 37 37 37 77 74 2e 63 6f 6d 20 77 77 77 2e 37 37 37 77 74 2e 63 6f 6d 20 37 39 2e 73 66 39 32 33 2e 63 6f 6d 20 73 66 37 37 37 2e 63 6f 6d 20 77 77 77 2e 73 66 39 39 2e 63 63 20 73 66 39 39 2e 63 63 20 77 77 77 2e 6d 65 69 73 68 69 70 61 69 2e 63 6f 6d 20 6a 64 6d 7a 64 2e 63 6f 6d } //2 112.175.69.77 pk555.com 777wt.com www.777wt.com 79.sf923.com sf777.com www.sf99.cc sf99.cc www.meishipai.com jdmzd.com
		$a_01_1 = {36 37 2e 31 39 38 2e 31 37 39 2e 37 35 20 77 77 77 2e 32 32 63 71 2e 63 6f 6d 20 77 77 77 2e 33 30 30 30 6f 6b 68 61 6f 73 66 2e 63 6f 6d 20 68 61 6f 31 31 39 2e 68 61 6f 6c 65 35 36 2e 63 6f 6d 20 77 77 77 2e 73 66 36 33 2e 63 6f 6d 20 34 35 36 6f 6b 2e 34 35 31 39 35 2e 63 6f 6d 20 37 39 2e 73 66 39 32 33 2e 63 6f 6d 20 77 77 77 2e 35 33 75 63 2e 63 6f 6d 20 35 33 75 63 2e 63 6f 6d 20 77 77 77 2e 72 65 63 61 69 72 65 6e 2e 63 6f 6d } //2 67.198.179.75 www.22cq.com www.3000okhaosf.com hao119.haole56.com www.sf63.com 456ok.45195.com 79.sf923.com www.53uc.com 53uc.com www.recairen.com
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 78 63 64 6c 71 } //1 Program Files\xcdlq
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}