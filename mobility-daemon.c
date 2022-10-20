#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf[2];
    sniff_for(BU, buf);

    return 0;
}