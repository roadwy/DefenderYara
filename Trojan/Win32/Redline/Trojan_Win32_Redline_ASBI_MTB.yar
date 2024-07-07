
rule Trojan_Win32_Redline_ASBI_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 62 6d 65 6b 62 6f 6e 76 64 62 7a 65 6d 73 72 69 6f 78 71 65 61 6d 77 69 6b 68 75 61 62 70 73 66 7a 69 66 72 72 69 6f 6a 6d 69 63 79 64 6e 69 6d 74 77 79 79 72 75 6f 61 77 71 78 77 72 61 } //1 mbmekbonvdbzemsrioxqeamwikhuabpsfzifrriojmicydnimtwyyruoawqxwra
		$a_01_1 = {6c 71 76 6f 69 6b 74 6a 6a 6b 6b 72 6d 6c 6c 6f 71 6d 6a 72 7a 65 72 63 67 66 7a 6a 7a 70 79 76 71 64 66 70 73 6c 62 61 7a 73 61 65 75 67 6b 79 6e 77 78 61 70 62 7a 72 6b 7a 68 67 76 77 7a 68 63 76 66 62 62 65 69 69 6d 75 74 7a 79 79 72 66 66 6d 71 67 } //1 lqvoiktjjkkrmlloqmjrzercgfzjzpyvqdfpslbazsaeugkynwxapbzrkzhgvwzhcvfbbeiimutzyyrffmqg
		$a_01_2 = {66 72 7a 75 64 71 62 67 66 6f 70 62 77 6e 6a 74 65 6b 6c 63 69 6b 7a 65 77 64 6e 66 69 6d 63 6c 74 72 75 } //1 frzudqbgfopbwnjteklcikzewdnfimcltru
		$a_01_3 = {79 74 77 6e 6f 71 61 68 6d 6d 6c 6f 78 66 66 75 79 69 6e 70 67 64 69 63 66 75 7a 67 61 74 69 70 78 69 6c 69 74 6c 70 72 6a 77 69 6d 68 67 66 76 76 6a 71 75 61 75 78 6e 65 77 73 6b 78 6d 6e 6c 6d 75 65 } //1 ytwnoqahmmloxffuyinpgdicfuzgatipxilitlprjwimhgfvvjquauxnewskxmnlmue
		$a_01_4 = {65 62 68 72 76 6d 62 74 69 66 78 6e 70 64 6f 66 6a 66 63 75 6c 76 67 64 7a 64 62 7a 6f 66 69 79 65 69 69 63 61 75 77 70 77 6d 71 66 7a 67 73 66 78 66 69 63 78 68 76 79 64 } //1 ebhrvmbtifxnpdofjfculvgdzdbzofiyeiicauwpwmqfzgsfxficxhvyd
		$a_01_5 = {7a 75 6e 75 70 65 6b 75 78 69 79 75 78 61 78 75 6a 69 6d 69 78 75 79 75 7a 61 79 65 66 75 73 65 } //1 zunupekuxiyuxaxujimixuyuzayefuse
		$a_01_6 = {72 61 78 6f 78 69 74 69 74 75 70 75 6e 6f 73 6f 74 75 76 20 63 65 6a 61 7a 6f 74 75 6b 65 63 69 6d 61 72 6f 7a } //1 raxoxititupunosotuv cejazotukecimaroz
		$a_01_7 = {6a 69 6c 61 72 75 6a 69 67 65 78 69 67 65 20 63 61 74 61 6b 20 77 6f 6c 75 6d 75 76 69 64 75 68 69 77 69 6d 6f 73 75 67 69 6e 65 6a 6f 6e 69 73 65 72 61 6d 75 } //1 jilarujigexige catak wolumuviduhiwimosuginejoniseramu
		$a_01_8 = {77 65 67 65 66 75 62 6f 6a 75 64 65 63 65 6a 69 20 77 75 76 65 77 61 66 69 6d 61 6d 69 76 6f 64 61 62 61 6d 65 66 61 72 6f 6b 65 66 65 72 6f 62 6f } //1 wegefubojudeceji wuvewafimamivodabamefarokeferobo
		$a_01_9 = {7a 65 67 65 6b 6f 73 61 78 75 6d 61 6d 69 72 65 79 69 73 75 77 75 78 75 68 65 7a 65 78 69 } //1 zegekosaxumamireyisuwuxuhezexi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}